package bo.edu.ucb.microservices.core.msreview;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import bo.edu.ucb.microservices.core.msreview.model.Review;
import bo.edu.ucb.microservices.core.msreview.repository.ReviewRepository;

@DataJpaTest
@Transactional(propagation = Propagation.NOT_SUPPORTED)
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
public class PersistenceTests extends PostgreSqlTestBase{
	  @Autowired
	  private ReviewRepository repository;

	  private Review savedEntity;

	  @BeforeEach
	  void setupDb() {
	    repository.deleteAll();

	    Review entity = new Review(1, 2, "a", "s", "c");
	    savedEntity = repository.save(entity);

	    assertEqualsReview(entity, savedEntity);
	  }


	  @Test
	  void create() {

	    Review newEntity = new Review(1, 3, "a", "s", "c");
	    repository.save(newEntity);

	    Review foundEntity = repository.findById(newEntity.getId()).get();
	    assertEqualsReview(newEntity, foundEntity);

	    assertEquals(2, repository.count());
	  }

	  @Test
	  void update() {
	    savedEntity.setAuthor("a2");
	    repository.save(savedEntity);

	    Review foundEntity = repository.findById(savedEntity.getId()).get();
	    assertEquals(1, (long)foundEntity.getVersion());
	    assertEquals("a2", foundEntity.getAuthor());
	  }

	  @Test
	  void delete() {
	    repository.delete(savedEntity);
	    assertFalse(repository.existsById(savedEntity.getId()));
	  }

	  @Test
	  void getByProductId() {
	    List<Review> entityList = repository.findByProductId(savedEntity.getProductId());

	    assertThat(entityList, hasSize(1));
	    assertEqualsReview(savedEntity, entityList.get(0));
	  }

	  @Test
	  void duplicateError() {
	    assertThrows(DataIntegrityViolationException.class, () -> {
	      Review entity = new Review(1, 2, "a", "s", "c");
	      repository.save(entity);
	    });

	  }

	  @Test
	  void optimisticLockError() {

	    Review entity1 = repository.findById(savedEntity.getId()).get();
	    Review entity2 = repository.findById(savedEntity.getId()).get();

	    entity1.setAuthor("a1");
	    repository.save(entity1);

	    assertThrows(OptimisticLockingFailureException.class, () -> {
	      entity2.setAuthor("a2");
	      repository.save(entity2);
	    });

	    // Get the updated entity from the database and verify its new sate
	    Review updatedEntity = repository.findById(savedEntity.getId()).get();
	    assertEquals(1, (int)updatedEntity.getVersion());
	    assertEquals("a1", updatedEntity.getAuthor());
	  }

	  private void assertEqualsReview(Review expectedEntity, Review actualEntity) {
	    assertEquals(expectedEntity.getId(),        actualEntity.getId());
	    assertEquals(expectedEntity.getVersion(),   actualEntity.getVersion());
	    assertEquals(expectedEntity.getProductId(), actualEntity.getProductId());
	    assertEquals(expectedEntity.getReviewId(),  actualEntity.getReviewId());
	    assertEquals(expectedEntity.getAuthor(),    actualEntity.getAuthor());
	    assertEquals(expectedEntity.getSubject(),   actualEntity.getSubject());
	    assertEquals(expectedEntity.getContent(),   actualEntity.getContent());
	  }
}
